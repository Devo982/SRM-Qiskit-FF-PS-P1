#!/usr/bin/env bash
# QFF 2026 PS-P1 - Intel Mac (x86_64) Phase 2 environment bootstrap
#
# WHY THIS EXISTS (verified against PyPI on 2026-10-29):
#   cryptography==50.0.2 ships macOS wheels for arm64 ONLY
#   (macosx_11_0_arm64). There is no macOS x86_64 wheel for ANY Python
#   version, so on Intel Macs uv/pip must build the sdist from source.
#   That build needs OpenSSL headers/libs, and this machine has no
#   Homebrew - so this script builds a STATIC OpenSSL 3.5 LTS into
#   ~/.local with nothing but the Xcode Command Line Tools, then
#   installs the kit-pinned package set into .venv-qff26.
#
# The kit pin (cryptography==50.0.2) is NOT changed. Judges on
# arm64-macOS / Linux / Windows get prebuilt wheels and are unaffected.
#
# USAGE: run from your repo root (the directory containing .venv-qff26):
#   bash QFF2026_intel_mac_env_setup.sh
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.9}"
PREFIX="$HOME/.local/openssl-${OPENSSL_VERSION}"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }

say "0/5 Preflight"
if [[ "$(uname -s)" != "Darwin" ]]; then echo "This script targets macOS only."; exit 1; fi
if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "Not an Intel Mac (arch: $(uname -m)); arm64 Macs get prebuilt wheels, no fix needed."
  exit 1
fi
for tool in clang make perl curl tar; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Missing tool: $tool (install Xcode CLT first: xcode-select --install)"; exit 1; }
done
ok "Darwin x86_64, toolchain present (clang/make/perl/curl/tar)"

say "1/5 OpenSSL ${OPENSSL_VERSION} (static, no-shared) -> ${PREFIX}"
if [[ -f "${PREFIX}/lib/libssl.a" ]]; then
  ok "Already built, skipping (delete ${PREFIX} to force a rebuild)"
else
  WORK="$HOME/.local/src/openssl-${OPENSSL_VERSION}"
  mkdir -p "$HOME/.local/src" "$WORK"
  if [[ ! -f "$HOME/.local/src/openssl-${OPENSSL_VERSION}.tar.gz" ]]; then
    curl -fL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
      -o "$HOME/.local/src/openssl-${OPENSSL_VERSION}.tar.gz"
  fi
  tar -xzf "$HOME/.local/src/openssl-${OPENSSL_VERSION}.tar.gz" -C "$WORK" --strip-components=1
  if ! ( cd "$WORK" && \
         ./Configure darwin64-x86_64-cc no-shared \
           --prefix="$PREFIX" --openssldir="$PREFIX/ssl" && \
         make -j"$JOBS" && \
         make install_sw ) > "$HOME/.local/src/openssl-build.log" 2>&1; then
    echo "OpenSSL build failed - last 40 log lines:"
    tail -40 "$HOME/.local/src/openssl-build.log"
    exit 1
  fi
  ok "Built & installed (static libs only -> no runtime dylib dependencies)"
fi

say "2/5 Export OpenSSL build env (persisted to ~/.qff26-openssl-env.sh)"
cat > "$HOME/.qff26-openssl-env.sh" <<EOF
export OPENSSL_DIR="$PREFIX"
export OPENSSL_LIB_DIR="$PREFIX/lib"
export OPENSSL_INCLUDE_DIR="$PREFIX/include"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export OPENSSL_STATIC=1
EOF
# shellcheck source=/dev/null
source "$HOME/.qff26-openssl-env.sh"
ok "OPENSSL_DIR=$OPENSSL_DIR (static linking forced via OPENSSL_STATIC=1)"

say "3/5 Install pinned deps into .venv-qff26"
if [[ ! -d "${PWD}/.venv-qff26" ]]; then
  echo "Run this script from your repo root (the directory containing .venv-qff26)."
  exit 1
fi
# shellcheck source=/dev/null
source .venv-qff26/bin/activate
uv pip install "cryptography==50.0.2" psutil numpy pandas matplotlib pqcrypto
ok "uv install finished"

say "4/5 Smoke test: ML-KEM-768 / ML-DSA-65 / X25519 / Ed25519 / HKDF / AES-256-GCM"
python - <<'QFF_EOF'
import sys, cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

k = mlkem.MLKEM768PrivateKey.generate()
shared, ct = k.public_key().encapsulate()
assert k.decapsulate(ct) == shared

s = mldsa.MLDSA65PrivateKey.generate()
sig = s.sign(b"qff26-smoke-test")
s.public_key().verify(sig, b"qff26-smoke-test")

x = x25519.X25519PrivateKey.generate()
assert len(x.exchange(x.public_key())) == 32
e = ed25519.Ed25519PrivateKey.generate()
e.public_key().verify(e.sign(b"x"), b"x")

key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qff26").derive(shared)
aes = AESGCM(key)
blob = aes.encrypt(b"\x00" * 12, b"hello", None)
assert aes.decrypt(b"\x00" * 12, blob, None) == b"hello"

print(f"READY - python {sys.version.split()[0]} | cryptography {cryptography.__version__} | "
      f"ML-KEM-768 OK | ML-DSA-65 OK | X25519 OK | Ed25519 OK | HKDF+AES-256-GCM OK")
QFF_EOF
ok "All required primitives verified"

say "5/5 Persist exports in ~/.zshrc (so future builds find OpenSSL)"
if ! grep -q "qff26-openssl-env" "$HOME/.zshrc" 2>/dev/null; then
  printf '\n# QFF26 PS-P1: static OpenSSL for cryptography sdist builds (Intel Mac)\nsource "$HOME/.qff26-openssl-env.sh"\n' >> "$HOME/.zshrc"
  ok "Added 'source ~/.qff26-openssl-env.sh' to ~/.zshrc"
else
  ok "~/.zshrc already references the env file"
fi

cat <<EOF

Setup complete. Note for the technical report / README:
  cryptography==50.0.2 has no macOS x86_64 wheel (PyPI: arm64-only for macOS).
  On this Intel Mac it is built from sdist against a static OpenSSL
  ${OPENSSL_VERSION} installed at ${PREFIX}.
  The kit pin is unchanged; other platforms use prebuilt wheels.
EOF
