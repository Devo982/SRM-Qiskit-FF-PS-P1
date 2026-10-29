#!/usr/bin/env bash
# QFF 2026 PS-P1 - Phase 2 scaffold (pre-approval-safe package)
#
# Creates ONLY design-independent artifacts:
#   - directory skeleton (mirrors protocol design v2 naming)
#   - requirements.txt (kit pin cryptography==50.0.2 + analysis stack, exact pins)
#   - .gitignore additions (payloads *.bin, bench raw, logs/figures)
#   - common/env_check.py  -> prints "READY - environment is correct."
#                             writes platform_A_info.json at repo root
#   - docs/INTEGRATION_CONTRACT.md (security invariants final, API marked DRAFT)
#
# It writes NO protocol/handshake code (that waits for design v2 sign-off).
# Idempotent: safe to re-run.
set -euo pipefail

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }

say "0/6 Preflight"
REPO="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO" ]]; then echo "Error: not inside a git repository. Run from the repo root."; exit 1; fi
REMOTE="$(git -C "$REPO" remote get-url origin 2>/dev/null || true)"
if [[ "$REMOTE" != *"Devo982/SRM-Qiskit-FF-PS-P1"* ]]; then
  echo "Error: origin ($REMOTE) is not Devo982/SRM-Qiskit-FF-PS-P1 - refusing to write."; exit 1
fi
cd "$REPO"
[[ -d "Phase One" ]] || echo "  warn: 'Phase One/' not found (expected from the archive step)"
ok "repo root: $REPO"

say "1/6 Directory skeleton"
mkdir -p common docs protocol cli scripts tests bench results data/payloads
for d in protocol cli scripts tests bench results data/payloads; do
  [[ -e "$d/.gitkeep" ]] || : > "$d/.gitkeep"
done
ok "common/ docs/ protocol/ cli/ scripts/ tests/ bench/ results/ data/payloads/"

say "2/6 requirements.txt (exact pins from the validated environment)"
cat > requirements.txt <<'EOF'
# QFF 2026 PS-P1 - Phase 2 requirements
# Python 3.10-3.13 supported (validated on CPython 3.13.17, macOS x86_64).

# Kit pin - do not change:
cryptography==50.0.2

# Analysis / benchmarking stack (exact versions of the validated env):
psutil==7.2.2
numpy==2.5.4
pandas==3.1.0
matplotlib==3.11.2

# Optional per kit FAQ (pqcrypto is NOT required for PS-P1):
# pqcrypto==1.0.0

# Platform note (Intel macOS only): cryptography 50.0.2 publishes no macOS
# x86_64 wheel, so it is built from sdist against a local static OpenSSL 3.x
# (source ~/.qff26-openssl-env.sh before installing - see README platform
# notes). Every other platform installs prebuilt wheels directly.
EOF
ok "requirements.txt written"

say "3/6 .gitignore additions (idempotent)"
if ! grep -q "Phase 2 (PS-P1) additions" .gitignore; then
  cat >> .gitignore <<'EOF'

# --- Phase 2 (PS-P1) additions ---
data/payloads/*.bin
bench/raw/
results/logs/
results/figures/
EOF
  ok "appended Phase 2 section"
else
  ok "already present, skipped"
fi

say "4/6 common/env_check.py"
cat > common/env_check.py <<'PYEOF'
#!/usr/bin/env python3
"""QFF 2026 PS-P1 - Phase 2 environment check (kit contract).

Usage:  python common/env_check.py
OK:     prints "READY - environment is correct." and writes
        platform_A_info.json at the repository root. Exit 0.
Fail:   prints "FAIL - <reason>" (+ hint). Exit 1.
"""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from importlib.metadata import version as _dist_version
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUIRED_CRYPTOGRAPHY = "50.0.2"
SUPPORTED_PYTHON = {(3, 10), (3, 11), (3, 12), (3, 13)}
REQUIRED_ANALYSIS = ("psutil", "numpy", "pandas", "matplotlib")


def fail(msg: str, hint: str | None = None) -> None:
    print(f"FAIL - {msg}")
    if hint:
        print(hint)
    sys.exit(1)


def main() -> None:
    # 1) Python version (kit: 3.10-3.13, recommends 3.13)
    v = sys.version_info
    if (v.major, v.minor) not in SUPPORTED_PYTHON:
        fail(f"Python {v.major}.{v.minor} not supported (need 3.10-3.13; kit recommends 3.13)")

    # 2) cryptography, exact kit pin
    try:
        import cryptography
    except Exception as exc:  # noqa: BLE001
        hint = None
        if platform.system() == "Darwin" and platform.machine() == "x86_64":
            hint = ("Hint (Intel macOS): cryptography 50.0.2 ships no macOS x86_64 wheel. "
                    "Build from sdist: source ~/.qff26-openssl-env.sh && "
                    "uv pip install -r requirements.txt (see README platform notes).")
        fail(f"cryptography not importable: {exc}", hint)
    if cryptography.__version__ != REQUIRED_CRYPTOGRAPHY:
        fail(f"cryptography {cryptography.__version__} found; the kit pins {REQUIRED_CRYPTOGRAPHY}")

    # 3) Required primitive smoke test
    verified: list[str] = []
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, mldsa, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        k = mlkem.MLKEM768PrivateKey.generate()
        ss, ct = k.public_key().encapsulate()
        assert k.decapsulate(ct) == ss
        verified.append("ML-KEM-768")

        s = mldsa.MLDSA65PrivateKey.generate()
        sig = s.sign(b"env-check")
        s.public_key().verify(sig, b"env-check")
        verified.append("ML-DSA-65")

        x = x25519.X25519PrivateKey.generate()
        assert len(x.exchange(x.public_key())) == 32
        verified.append("X25519")

        e = ed25519.Ed25519PrivateKey.generate()
        e.public_key().verify(e.sign(b"env-check"), b"env-check")
        verified.append("Ed25519")

        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"qff26", info=b"env-check").derive(ss)
        verified.append("HKDF-SHA256")

        aes = AESGCM(key)
        blob = aes.encrypt(b"\x00" * 12, b"env-check", b"aad")
        assert aes.decrypt(b"\x00" * 12, blob, b"aad") == b"env-check"
        verified.append("AES-256-GCM")
    except Exception as exc:  # noqa: BLE001
        fail(f"required primitive smoke test failed: {exc}")

    # 4) pqcrypto (optional per kit FAQ - report only, never fails)
    pq_ver: str | None = None
    try:
        import pqcrypto  # noqa: F401
        pq_ver = _dist_version("pqcrypto")
    except Exception:  # noqa: BLE001
        pass

    # 5) Analysis stack (required; delivered via requirements.txt)
    missing = [m for m in REQUIRED_ANALYSIS if not _importable(m)]
    if missing:
        fail(f"missing analysis dependencies: {', '.join(missing)} (install via requirements.txt)")

    # 6) Honest platform provenance for platform_A_info.json
    openssl_txt = None
    try:
        from cryptography.hazmat.backends.openssl import backend
        openssl_txt = backend.openssl_version_text()
    except Exception:  # noqa: BLE001
        openssl_txt = "OpenSSL (version string unavailable via backend)"
    is_intel_mac = platform.system() == "Darwin" and platform.machine() == "x86_64"
    origin = ("sdist source build (no official macOS x86_64 wheel for cryptography 50.0.2); "
              "statically linked local OpenSSL - see README platform notes"
              if is_intel_mac else "prebuilt wheel")

    info = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kit": "Qiskit Fall Fest 2026 - PS-P1 Quantum-Safe Secure Communication Channel",
        "phase": 2,
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "description": platform.platform(),
        },
        "crypto": {
            "cryptography_version": cryptography.__version__,
            "openssl_runtime": openssl_txt,
            "install_origin": origin,
            "pqcrypto_version": pq_ver,
            "pqcrypto_required_for_PS_P1": False,
        },
        "primitives_verified": verified,
    }
    out = REPO_ROOT / "platform_A_info.json"
    out.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

    print(f"environment: python {platform.python_version()} | cryptography {cryptography.__version__}"
          f" | primitives: {', '.join(verified)} | wrote {out.name}")
    print("READY - environment is correct.")


def _importable(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    main()
PYEOF
ok "common/env_check.py written"

say "5/6 docs/INTEGRATION_CONTRACT.md (invariants final, API marked DRAFT)"
cat > docs/INTEGRATION_CONTRACT.md <<'MDEOF'
# Integration Contract - UX / Developer-Experience Layer <=> PS-P1 Secure Channel

> Status: **DRAFT v0.1** - security invariants (§2) are final and may be relied on;
> the API surface (§4) is fixed by protocol design v2 at the naming level and awaits
> design sign-off before implementation lands.
> Owner: protocol lead (this repo). Consumer: UX/demo team.

## 1. Purpose

This document is the ONLY boundary between the user-facing layer and the
quantum-safe channel implementation. The UX layer drives demos and the developer
experience; it must never need - and must never be able - to touch cryptographic
secrets. Everything the UX layer may do is expressible through the façade in §4.

## 2. Security invariants (non-negotiable)

- **I1** The UX layer never imports crypto modules and never observes private keys,
  shared secrets, traffic keys, or nonces - in memory, files, logs, or UI.
- **I2** All private key material lives under `identities/` (git-ignored) and is
  created only by `scripts/provision_identities.py`. `trust_store.json` (public
  verification keys only) is the single committed trust anchor.
- **I3** The UX layer interacts exclusively through the channel façade (§4):
  open / send / recv / close plus typed error names. No other import path is
  supported or stable.
- **I4** Logs and UI may display metadata only: state transitions, byte counts,
  suite id, failure category. Never key bytes; never plaintext of failed records.
- **I5** No API path bypasses trust-store lookup, signature verification, or the
  record replay window. There is no "insecure mode".

## 3. Suites (selected by local configuration; never negotiated on the wire)

| Suite id | KEM | Signature | KDF | AEAD |
|---|---|---|---|---|
| `QFF26-PQC-1` | ML-KEM-768 (FIPS 203) | ML-DSA-65 (FIPS 204) | HKDF-SHA256 | AES-256-GCM |
| `QFF26-CLASSICAL-1` | X25519 | Ed25519 | HKDF-SHA256 | AES-256-GCM |

## 4. API surface (naming fixed by design v2; signatures pending sign-off)

- `ClientChannel`, `ServerChannel`: one state machine per role,
  `INIT → ... → ESTABLISHED → CLOSED | FAILED(reason)`.
- Typed failures surfaced to UX: `PolicyViolation`, `UntrustedIdentity`,
  `AuthenticationFailure`, `TranscriptBindingError`, `HandshakeReplayDetected`,
  `RecordReplayDetected`, `RecordAuthenticationError`, `SessionExhausted`.
- CLI reference adapter: `cli/` (placeholder until the implementation package lands).

## 5. Test ownership

T1-T9 live in `tests/` and run via a single command; results append to
`results/security_tests.csv`. The UX layer consumes the CSV summary; it is never a
participant in the tests.

## 6. Change process

Any change to invariants I1-I5 or to the wire format requires a new signed revision
of this document and protocol-lead approval.
MDEOF
ok "docs/INTEGRATION_CONTRACT.md written"

say "6/6 Run env check (kit contract)"
if [[ -x ".venv-qff26/bin/python" ]]; then PY=".venv-qff26/bin/python"; else PY="python3"; fi
"$PY" common/env_check.py
ok "env check passed (exit 0)"

cat <<'EOF'

Scaffold complete. Review, then commit:
  git add -A
  git status --short
  git commit -m "phase2: scaffold, pinned requirements, env check, integration contract draft"
  git push origin main

NOT included by design (awaits protocol design v2 sign-off):
  scripts/provision_identities.py, protocol/ state machine, cli/ adapter,
  tests/ T1-T9 harness, README rewrite.
EOF
