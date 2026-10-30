#!/usr/bin/env python3
"""QFF 2026 PS-P1 - automated security test battery T1-T9 (design v2 section 7).

Single command:
    python -m tests.run_security_tests        (repo root)
    python tests/run_security_tests.py        (also works)

Every fault is injected on the WIRE between two real endpoints - no test calls
internal functions with pre-broken values. Results are written to
results/security_tests.csv and printed as a table.

Requires: scripts/provision_identities.py to have been run once (identities/ +
trust_store.json). This tool asserts via PUBLIC confirmation status only
(states, failure categories, sizes) - key bytes are never printed.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from common.official_payloads import PAYLOADS, ensure_payloads  # noqa: E402
from cryptography.exceptions import InvalidTag
from protocol.errors import RecordAuthenticationError
from protocol import records as rec  # noqa: E402
from protocol.channels import ClientChannel, ServerChannel  # noqa: E402
from protocol.suites import (  # noqa: E402
    QFF26_CLASSICAL_1,
    QFF26_PQC_1,
    SUITES,
    load_identity_private_keys,
    sig_generate,
)
from protocol.tlv import TAG_ID_C, TAG_ID_S, TAG_KEM_CT, TAG_KEM_PK_C  # noqa: E402
from protocol.tlv import (  # noqa: E402
    TAG_NONCE_C,
    TAG_NONCE_S,
    TAG_PROTO_VERSION,
    TAG_SIG_C,
    TAG_SIG_S,
    TAG_SUITE_ID,
)
from protocol.wire import Endpoint, InMemoryWire  # noqa: E402
from tests.harness import (  # noqa: E402
    duplicate_frame,
    extract_field,
    flip_handshake_field,
    flip_record_byte,
    make_channels,
    run_handshake,
    substitute_handshake_field,
)

ROWS: list[dict] = []
_FAILURES = 0


def check(tid: str, sub: str, suite: str, scenario: str, expected: str,
          observed: str, ok: bool, detail: str = "") -> bool:
    global _FAILURES
    if not ok:
        _FAILURES += 1
    ROWS.append({
        "test_id": tid, "sub": sub, "suite": suite, "scenario": scenario,
        "expected": expected, "observed": observed,
        "status": "PASS" if ok else "FAIL",
        "detail": detail, "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    mark = "PASS" if ok else "FAIL"
    print(f"  [{tid}/{sub}] {mark:<4} {scenario}  (expected {expected}; observed {observed})")
    if not ok and detail:
        print(f"          detail: {detail}")
    return ok


# ---------------------------------------------------------------------------
# Context: trust store + identity private keys (never printed)
# ---------------------------------------------------------------------------

def load_context() -> tuple[dict, dict]:
    trust_path = REPO_ROOT / "trust_store.json"
    idir = REPO_ROOT / "identities"
    if not trust_path.exists() or not (idir / "alice.json").exists():
        raise SystemExit(
            "FAIL - identities not provisioned. Run: python scripts/provision_identities.py"
        )
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    return trust, {"alice": idir / "alice.json", "bob": idir / "bob.json"}


def fresh_handshake(suite, trust, a_sk, b_sk, **kw):
    client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk, **kw)
    run_handshake(client, server, wire)
    return client, server, wire


# ---------------------------------------------------------------------------
# T1 - honest handshake + official payloads + authenticated close
# ---------------------------------------------------------------------------

def t1(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    client, server, wire = fresh_handshake(suite, trust, a_sk, b_sk)
    check("T1", "a", sid, "honest handshake establishes both endpoints",
          "both ESTABLISHED",
          f"client={client.state},server={server.state}",
          client.established and server.established)

    payloads = ensure_payloads()
    ok = True
    detail = ""
    for name, size in PAYLOADS:
        data = payloads[name]
        expected_sha = hashlib.sha256(data).hexdigest()
        client.send(data)
        wire.pump(client, server)
        got = server.recv()
        got_sha = hashlib.sha256(got).hexdigest() if got is not None else "none"
        if got != data:
            ok, detail = False, f"c2s {name}: byte comparison failed"
            break
        if got_sha != expected_sha:
            ok, detail = False, f"c2s {name}: SHA-256 mismatch"
            break
        server.send(data)
        wire.pump(client, server)
        got2 = client.recv()
        if got2 != data or hashlib.sha256(got2).hexdigest() != expected_sha:
            ok, detail = False, f"s2c {name}: byte/SHA verification failed"
            break
    check("T1", "b", sid, "3 official payloads (1KB/100KB/10MB), both directions, "
          "byte-level + SHA-256 vs payload_sha256.txt",
          "6/6 verified", "6/6 verified" if ok else "mismatch", ok, detail)

    client.close()
    wire.pump(client, server)
    check("T1", "c", sid, "authenticated close record tears down the peer",
          "server CLOSED", f"server={server.state}", server.state == "CLOSED")


# ---------------------------------------------------------------------------
# T2 - transcript-field bit flips (parametrized, abort at owning step)
# ---------------------------------------------------------------------------

T2_CASES = [
    ("kem_pk_C", "c2s", 0, TAG_KEM_PK_C, "client", "AuthenticationFailure"),
    ("nonce_C", "c2s", 0, TAG_NONCE_C, "client", "AuthenticationFailure"),
    ("id_C", "c2s", 0, TAG_ID_C, "server", "UntrustedIdentity"),
    ("proto_version", "c2s", 0, TAG_PROTO_VERSION, "server", "PolicyViolation"),
    ("suite_id", "c2s", 0, TAG_SUITE_ID, "server", "PolicyViolation"),
    ("kem_ct", "s2c", 0, TAG_KEM_CT, "client", "AuthenticationFailure"),
    ("nonce_S", "s2c", 0, TAG_NONCE_S, "client", "AuthenticationFailure"),
    ("id_S", "s2c", 0, TAG_ID_S, "client", "UntrustedIdentity"),
]


def t2(suite, trust, a_sk, b_sk) -> None:
    for label, direction, idx, tag, side, expected in T2_CASES:
        _t2_case(suite, trust, a_sk, b_sk, label, direction, idx, tag, side, expected)


def _t2_case(suite, trust, a_sk, b_sk, label, direction, idx, tag, side, expected) -> None:
    sid = suite.suite_id
    client, server, wire = make_channels(sid, trust, a_sk, b_sk)
    wire.add_fault(direction, idx, flip_handshake_field(tag))
    run_handshake(client, server, wire)
    observed_chan = client if side == "client" else server
    other = server if side == "client" else client
    cat = observed_chan.failure_category or f"no-failure(state={observed_chan.state})"
    ok = (observed_chan.failure_category == expected
          and not client.established and not server.established)
    check("T2", label, sid, f"bit-flip {label} on wire -> abort at owning step, "
          "traffic keys never established", f"{side}:{expected},no-establishment",
          f"{side}:{cat},established={client.established or server.established}", ok,
          observed_chan.failure_detail or "")


# ---------------------------------------------------------------------------
# T3 - signature flips
# ---------------------------------------------------------------------------

def t3(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # sig_S flip in M2
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    wire.add_fault("s2c", 0, flip_handshake_field(TAG_SIG_S))
    run_handshake(client, server, wire)
    check("T3", "sig_S", sid, "bit-flip sig_S -> AuthenticationFailure at client",
          "client:AuthenticationFailure",
          f"client:{client.failure_category}",
          client.failure_category == "AuthenticationFailure")
    # sig_C flip in M3 (c2s frame #1)
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    wire.add_fault("c2s", 1, flip_handshake_field(TAG_SIG_C))
    run_handshake(client, server, wire)
    check("T3", "sig_C", sid, "bit-flip sig_C -> AuthenticationFailure at server",
          "server:AuthenticationFailure",
          f"server:{server.failure_category}",
          server.failure_category == "AuthenticationFailure")


def _mk(suite, trust, a_sk, b_sk, **kw):
    client, server, wire = make_channels(suite.suite_id, trust, a_sk, b_sk, **kw)
    return client, server, wire


# ---------------------------------------------------------------------------
# T4/T5 - record-layer flips (ciphertext / tag / header AAD / direction)
# ---------------------------------------------------------------------------

def t4_t5(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    cases = [
        (
            "T4", "record_ct",
            lambda i: flip_record_byte(rec.HEADER_LEN),
            "RecordAuthenticationError", "InvalidTag",
        ),
        (
            "T5", "gcm_tag",
            lambda i: flip_record_byte(-1),
            "RecordAuthenticationError", "InvalidTag",
        ),
        (
            "T5", "header_aad",
            # Byte 2 is the record-type field: this preserves structurally
            # valid version/direction/length fields but changes authenticated AAD.
            lambda i: flip_record_byte(2),
            "RecordAuthenticationError", "InvalidTag",
        ),
        (
            "T5", "header_version",
            lambda i: flip_record_byte(0),
            "RecordAuthenticationError", "none",
        ),
        (
            "T5", "header_direction",
            lambda i: flip_record_byte(3),
            "TranscriptBindingError", "before-aead",
        ),
    ]

    for tid, label, fault, expected, expected_cause in cases:
        client, server, wire = _mk(suite, trust, a_sk, b_sk)
        run_handshake(client, server, wire)

        # Record sequence numbers follow handshake frames, so use the
        # next actual c2s wire index.
        idx = wire.counts["c2s"]
        wire.add_fault("c2s", idx, fault(idx))
        client.send(b"tamper-test")

        observed_causes = []
        original_open_record = rec.open_record

        def observing_open_record(*args, **kwargs):
            try:
                return original_open_record(*args, **kwargs)
            except RecordAuthenticationError as exc:
                cause = exc.__cause__
                if isinstance(cause, InvalidTag):
                    observed_causes.append("InvalidTag")
                elif cause is None:
                    observed_causes.append(None)
                else:
                    observed_causes.append(type(cause).__name__)
                raise

        # Observe the real protocol path, then restore the original function
        # even if delivery fails.
        rec.open_record = observing_open_record
        try:
            wire.pump(client, server)
        finally:
            rec.open_record = original_open_record

        cat = server.failure_category or f"no-failure(state={server.state})"
        withheld = server.recv() is None

        if expected_cause == "InvalidTag":
            cause_ok = observed_causes == ["InvalidTag"]
            cause_text = (
                f"underlying_cause={observed_causes[0]}"
                if observed_causes else "underlying_cause=missing"
            )
            expected_text = (
                f"server:{expected}(cause=InvalidTag),plaintext-withheld"
            )
        elif expected_cause == "none":
            cause_ok = observed_causes == [None]
            cause_text = f"underlying_cause={observed_causes}"
            expected_text = (
                f"server:{expected},plaintext-withheld "
                "(structural rejection before AEAD)"
            )
        else:
            cause_ok = observed_causes == []
            cause_text = "AEAD=not-reached"
            expected_text = (
                f"server:{expected},plaintext-withheld "
                "(direction check before AEAD)"
            )

        ok = (
            server.failure_category == expected
            and withheld
            and cause_ok
        )

        scenario = (
            f"record tamper ({label}) rejected, plaintext withheld; "
            f"{cause_text}"
        )
        check(
            tid, label, sid, scenario,
            expected_text,
            f"server:{cat},withheld={withheld},{cause_text}",
            ok,
            server.failure_detail or "",
        )


# ---------------------------------------------------------------------------
# T6 - untrusted identity (attacker with own valid key) rejected at lookup
# ---------------------------------------------------------------------------

def t6(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    _atk_vk, atk_sk = sig_generate(suite)
    client, server, wire = make_channels(
        sid, trust, atk_sk, b_sk,
        client_identity="client:mallory")
    run_handshake(client, server, wire)
    detail = server.failure_detail or ""
    ok = (server.failure_category == "UntrustedIdentity"
          and not server.established and not client.established)
    check("T6", "attacker-id", sid,
          "attacker identity + own valid key -> UntrustedIdentity at trust-store "
          "lookup, before any signature math",
          "server:UntrustedIdentity", f"server:{server.failure_category}", ok, detail)


# ---------------------------------------------------------------------------
# T7 - role swap + old-signature splice
# ---------------------------------------------------------------------------

def t7(suite, trust, id_paths, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # (a) role swap: bob initiates as "client" using his genuine key
    bob_sk = load_identity_private_keys(id_paths["bob"], suite)
    client, server, wire = make_channels(
        sid, trust, bob_sk, b_sk, client_identity="server:bob")
    run_handshake(client, server, wire)
    ok = (server.failure_category == "UntrustedIdentity"
          and not server.established)
    check("T7", "a-role-swap", sid,
          "role swap (server:bob initiates as client) -> rejected at lookup",
          "server:UntrustedIdentity", f"server:{server.failure_category}", ok,
          server.failure_detail or "")

    # (b) genuine old sig_S spliced into a fresh session
    _c, _s, wire_a = _mk(suite, trust, a_sk, b_sk)
    run_handshake(_c, _s, wire_a)
    m2_a = next(f for d, i, f in wire_a.log if d == "s2c" and i == 0)
    old_sig = extract_field(m2_a, TAG_SIG_S)

    client, server, wire_b = _mk(suite, trust, a_sk, b_sk)
    wire_b.add_fault("s2c", 0, substitute_handshake_field(TAG_SIG_S, old_sig))
    run_handshake(client, server, wire_b)
    ok = (client.failure_category == "AuthenticationFailure"
          and not client.established and not server.established)
    check("T7", "b-sig-splice", sid,
          "genuine old sig_S spliced into a fresh session -> transcript binding rejects",
          "client:AuthenticationFailure", f"client:{client.failure_category}", ok,
          client.failure_detail or "")


# ---------------------------------------------------------------------------
# T8 - replay: app record, full handshake, M1 replay w/ cache
# ---------------------------------------------------------------------------

def t8(suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # (a) app-record replay: byte-identical duplicate arrives at the receiver
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    run_handshake(client, server, wire)
    idx = wire.counts["c2s"]
    wire.add_fault("c2s", idx, duplicate_frame())
    client.send(b"replay-me")
    wire.pump(client, server)
    got = server.recv()
    ok = (server.failure_category == "RecordReplayDetected" and got == b"replay-me")
    check("T8", "a-record-replay", sid,
          "byte-identical app-record replay -> RecordReplayDetected before decrypt",
          "server:RecordReplayDetected,first-copy-delivered",
          f"server:{server.failure_category},first-copy={got!r}", ok,
          server.failure_detail or "")

    # (b) full old-session replay against a fresh server (no cache)
    _c, _s, wire_a = _mk(suite, trust, a_sk, b_sk)
    run_handshake(_c, _s, wire_a)
    old_m1 = next(f for d, i, f in wire_a.log if d == "c2s" and i == 0)
    old_m3 = next(f for d, i, f in wire_a.log if d == "c2s" and i == 1)

    wire_b = InMemoryWire()
    server_b = ServerChannel(
        suite_id=sid, trust_store=trust, identity="server:bob", sign_sk=b_sk,
        endpoint=wire_b.server_ep, enable_handshake_cache=False)
    server_b.on_frame(old_m1)          # fresh M2' generated (fresh nonce_S/ct/sig_S)
    server_b.on_frame(old_m3)          # replayed sig_C/fin_C are over a different T3
    ok = (server_b.failure_category == "AuthenticationFailure"
          and not server_b.established)
    check("T8", "b-handshake-replay", sid,
          "full old-session replay -> fails at M3 verification",
          "server:AuthenticationFailure", f"server:{server_b.failure_category}", ok,
          server_b.failure_detail or "")

    # (c) M1 replay with the (id_C, nonce_C) deployment cache shared across connections
    shared_cache: OrderedDict = OrderedDict()
    s1 = ServerChannel(suite_id=sid, trust_store=trust, identity="server:bob",
                       sign_sk=b_sk, endpoint=Endpoint("s1"),
                       handshake_cache=shared_cache)
    s1.on_frame(old_m1)  # first connection: accepted, cached
    s2 = ServerChannel(suite_id=sid, trust_store=trust, identity="server:bob",
                       sign_sk=b_sk, endpoint=Endpoint("s2"),
                       handshake_cache=shared_cache)
    s2.on_frame(old_m1)  # second connection, same M1 bytes: cache hit
    ok = s2.failure_category == "HandshakeReplayDetected"
    check("T8", "c-m1-replay-cache", sid,
          "M1 replay with (id_C, nonce_C) freshness cache -> HandshakeReplayDetected",
          "server:HandshakeReplayDetected", f"server:{s2.failure_category}", ok,
          s2.failure_detail or "")


# ---------------------------------------------------------------------------
# T9 - suite policy violations (before any crypto)
# ---------------------------------------------------------------------------

def t9(suite, other_suite, trust, a_sk, b_sk) -> None:
    sid = suite.suite_id
    # (a) unknown suite id on the wire
    client, server, wire = _mk(suite, trust, a_sk, b_sk)
    wire.add_fault("c2s", 0, substitute_handshake_field(TAG_SUITE_ID, b"QFF26-BOGUS-1"))
    run_handshake(client, server, wire)
    check("T9", "a-unknown-suite", sid,
          "unknown suite_id -> PolicyViolation before any crypto",
          "server:PolicyViolation", f"server:{server.failure_category}",
          server.failure_category == "PolicyViolation", server.failure_detail or "")

    # (b) server echo substituted to the other VALID suite; client policy allows one.
    # The client must reject the echoed suite via LOCAL POLICY - no fallback to
    # whatever the wire carried. (M1-side substitution is covered by T2/suite_id.)
    other_id = other_suite.suite_id.encode()
    client, server, wire = _mk(suite, trust, a_sk, b_sk,
                               client_allowed=frozenset([sid]),
                               server_allowed=frozenset(SUITES.keys()))
    wire.add_fault("s2c", 0, substitute_handshake_field(TAG_SUITE_ID, other_id))
    run_handshake(client, server, wire)
    ok = (client.failure_category == "PolicyViolation"
          and not client.established and not server.established)
    check("T9", "b-suite-echo-substitution", sid,
          "M2 echoes a different VALID suite -> client local policy rejects, no fallback",
          "client:PolicyViolation,no-establishment",
          f"client:{client.failure_category},established={client.established or server.established}",
          ok, client.failure_detail or "")

    # (c) A valid alternate suite in M1 must not override server local policy.
    other_a_sk = load_identity_private_keys(
        REPO_ROOT / "identities" / "alice.json", other_suite
    )
    wire = InMemoryWire()
    client = ClientChannel(
        suite_id=other_suite.suite_id,
        trust_store=trust,
        identity="client:alice",
        sign_sk=other_a_sk,
        endpoint=wire.client_ep,
        allowed_suites=frozenset(SUITES.keys()),
    )
    server = ServerChannel(
        suite_id=sid,
        trust_store=trust,
        identity="server:bob",
        sign_sk=b_sk,
        endpoint=wire.server_ep,
        allowed_suites=frozenset(SUITES.keys()),
    )

    client.start()
    wire.pump(client, server)

    ok = (
        server.failure_category == "PolicyViolation"
        and not client.established
        and not server.established
    )
    check(
        "T9",
        "c-server-local-policy-mismatch",
        sid,
        "M1 selects a valid suite different from server local policy",
        "server:PolicyViolation,no-establishment",
        f"server:{server.failure_category},client_established={client.established}",
        ok,
        server.failure_detail or "",
    )


# ---------------------------------------------------------------------------

def write_csv() -> Path:
    results_dir = REPO_ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Preserve every individual wire-level check in a detailed CSV.
    detail_fields = [
        "test_id", "sub", "suite", "scenario", "expected",
        "observed", "status", "detail", "timestamp_utc",
    ]
    detailed_out = results_dir / "security_tests_detailed.csv"
    with open(detailed_out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=detail_fields, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(ROWS)

    # Organizer template: one aggregate result for each T1-T9 category.
    template_fields = [
        "test_id", "description", "injected_fault",
        "expected", "observed", "result", "run_command",
    ]
    template_specs = [
        ("T1", "Honest run", "none",
         "handshake ok + payloads decrypt byte-exact"),
        ("T2", "Handshake tampering", "bit flip in KEM ciphertext",
         "abort"),
        ("T3", "Signature tampering", "bit flip in ML-DSA signature",
         "reject"),
        ("T4", "Ciphertext tampering", "bit flip in record ciphertext",
         "InvalidTag"),
        ("T5", "Tag/AAD tampering", "modified tag or header",
         "InvalidTag"),
        ("T6", "Untrusted identity", "attacker key not matching trust anchor",
         "reject"),
        ("T7", "Identity swap", "replayed signature in session naming other peer",
         "reject"),
        ("T8", "Replay", "resent record / old handshake",
         "reject or documented limitation"),
        ("T9", "Algorithm downgrade", "changed algorithm IDs",
         "reject"),
    ]

    successful_observations = {
        "T1": (
            "Both suites established successfully; all official payloads "
            "matched byte-for-byte and by SHA-256 in both directions "
            "(6/6 payload transfers per suite); authenticated close passed in both suites."
        ),
        "T2": (
            "All 16 handshake-message mutation checks aborted without "
            "traffic-key establishment."
        ),
        "T3": "All 4 signature-tampering checks were rejected.",
        "T4": (
            "Both suites observed underlying InvalidTag from AES-GCM, "
            "wrapped as RecordAuthenticationError; plaintext was withheld."
        ),
        "T5": (
            "GCM tag and authenticated-header mutations produced "
            "InvalidTag, wrapped as RecordAuthenticationError; malformed "
            "version/direction fields were rejected before AEAD, with "
            "plaintext withheld."
        ),
        "T6": (
            "Both suites rejected the untrusted attacker identity at "
            "trust-store lookup."
        ),
        "T7": (
            "Both role-swap checks and both signature-splice checks were "
            "rejected."
        ),
        "T8": (
            "Record replay, old-session handshake replay, and M1 replay "
            "were rejected in both suites (6/6 subchecks)."
        ),
        "T9": (
            "Unknown suite IDs, server-echo substitutions, and valid "
            "alternate-suite M1 messages conflicting with server local "
            "policy were rejected in both suites; no fallback occurred."
        ),
    }

    expected_subs = {
        "T1": {"a", "b", "c"},
        "T2": {
            "kem_pk_C", "nonce_C", "id_C", "proto_version",
            "suite_id", "kem_ct", "nonce_S", "id_S",
        },
        "T3": {"sig_S", "sig_C"},
        "T4": {"record_ct"},
        "T5": {"gcm_tag", "header_aad", "header_version", "header_direction"},
        "T6": {"attacker-id"},
        "T7": {"a-role-swap", "b-sig-splice"},
        "T8": {
            "a-record-replay", "b-handshake-replay",
            "c-m1-replay-cache",
        },
        "T9": {"a-unknown-suite", "b-suite-echo-substitution", "c-server-local-policy-mismatch"},
    }
    expected_suites = {"QFF26-PQC-1", "QFF26-CLASSICAL-1"}

    summary_rows = []
    for tid, description, injected_fault, expected in template_specs:
        matches = [row for row in ROWS if row["test_id"] == tid]
        failures = [row for row in matches if row["status"] != "PASS"]
        passed = len(matches) - len(failures)
        coverage_errors = []

        observed_suites = {row["suite"] for row in matches}
        if observed_suites != expected_suites:
            coverage_errors.append(
                f"expected suites {sorted(expected_suites)}, "
                f"found {sorted(observed_suites)}"
            )

        for suite_id in sorted(expected_suites):
            suite_rows = [
                row for row in matches if row["suite"] == suite_id
            ]
            actual_subs = [row["sub"] for row in suite_rows]
            actual_set = set(actual_subs)
            required_set = expected_subs[tid]

            if (
                len(actual_subs) != len(required_set)
                or actual_set != required_set
            ):
                missing = sorted(required_set - actual_set)
                unexpected = sorted(actual_set - required_set)
                duplicates = sorted(
                    sub for sub in actual_set
                    if actual_subs.count(sub) > 1
                )
                coverage_errors.append(
                    f"{suite_id}: incomplete/invalid coverage; "
                    f"missing={missing}, unexpected={unexpected}, "
                    f"duplicates={duplicates}"
                )

        all_pass = (
            bool(matches)
            and not failures
            and not coverage_errors
        )

        if all_pass:
            observed = (
                f"{successful_observations[tid]} "
                f"Coverage verified: {len(matches)} detailed checks "
                "across both suites."
            )
        else:
            issues = list(coverage_errors)
            if not matches:
                issues.append("no detailed checks recorded")
            if failures:
                failed_cases = "; ".join(
                    f'{row["suite"]}: {row["scenario"]} '
                    f'({row["status"]})'
                    for row in failures
                )
                issues.append(
                    f"{len(failures)} failed checks: {failed_cases}"
                )
            observed = (
                f"{passed}/{len(matches)} observed detailed checks passed. "
                + "; ".join(issues)
            )

        summary_rows.append({
            "test_id": tid,
            "description": description,
            "injected_fault": injected_fault,
            "expected": expected,
            "observed": observed,
            "result": "PASS" if all_pass else "FAIL",
            "run_command": "python -m tests.run_security_tests",
        })

    # This is the organizer-format results file.
    out = results_dir / "security_tests.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=template_fields, lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"Detailed subchecks written to {detailed_out}")
    return out


def main() -> None:
    t0 = time.perf_counter()
    print("QFF 2026 PS-P1 security test battery T1-T9 (wire-level fault injection)")
    trust, id_paths = load_context()
    ensure_payloads()

    for suite, other in [(QFF26_PQC_1, QFF26_CLASSICAL_1),
                         (QFF26_CLASSICAL_1, QFF26_PQC_1)]:
        a_sk = load_identity_private_keys(id_paths["alice"], suite)
        b_sk = load_identity_private_keys(id_paths["bob"], suite)
        print(f"\n== suite {suite.suite_id} ({suite.kem_name} + {suite.sig_name}) ==")
        t1(suite, trust, a_sk, b_sk)
        t2(suite, trust, a_sk, b_sk)
        t3(suite, trust, a_sk, b_sk)
        t4_t5(suite, trust, a_sk, b_sk)
        t6(suite, trust, a_sk, b_sk)
        t7(suite, trust, id_paths, a_sk, b_sk)
        t8(suite, trust, a_sk, b_sk)
        t9(suite, other, trust, a_sk, b_sk)

    out = write_csv()

    with out.open("r", newline="", encoding="utf-8") as fh:
        summary_rows = list(csv.DictReader(fh))

    expected_summary_ids = [f"T{i}" for i in range(1, 10)]
    actual_summary_ids = [row.get("test_id") for row in summary_rows]
    unexpected_detail_ids = sorted(
        {str(row.get("test_id")) for row in ROWS}
        - set(expected_summary_ids)
    )
    summary_structure_ok = (
        actual_summary_ids == expected_summary_ids
        and len(ROWS) == 54
        and not unexpected_detail_ids
    )
    coverage_failures = [
        row for row in summary_rows if row.get("result") != "PASS"
    ]

    elapsed = time.perf_counter() - t0
    total = len(ROWS)
    all_pass = (
        _FAILURES == 0
        and summary_structure_ok
        and not coverage_failures
    )

    status = "ALL TESTS PASSED" if all_pass else "FAILURES PRESENT"
    print(
        f"\n{status}: {total - _FAILURES}/{total} detailed checks "
        f"in {elapsed:.2f}s"
    )

    if not summary_structure_ok:
        print(
            "ERROR: organizer summary IDs/order or detailed-row inventory "
            "is invalid; "
            f"summary IDs={actual_summary_ids}, detailed rows={len(ROWS)}, "
            f"unexpected test IDs={unexpected_detail_ids}"
        )

    if coverage_failures:
        failed_ids = ", ".join(
            row["test_id"] for row in coverage_failures
        )
        print(
            f"Coverage/summary failures: "
            f"{len(coverage_failures)} ({failed_ids})"
        )

    print(f"results written to {out.relative_to(REPO_ROOT)}")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()

