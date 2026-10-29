#!/usr/bin/env bash
# QFF 2026 PS-P1 - interpreter probe + .venv creation
# Kit contract: Python 3.10-3.13 supported, 3.13 recommended; requirements use compatible minimums.
# Usage:
#   ./scripts/bootstrap_env.sh                  # probe + create/recreate .venv
#   ./scripts/bootstrap_env.sh --python PATH    # explicit interpreter override
set -euo pipefail

say() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  OK\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

RANGE_CHECK='import sys; assert sys.version_info[:2] in {(3,10),(3,11),(3,12),(3,13)}'
in_range() { "$1" -c "$RANGE_CHECK" >/dev/null 2>&1; }

# venv counts as created only if it also has a working pip (ensurepip present)
try_venv() {
  rm -rf .venv
  if "$1" -m venv .venv >/dev/null 2>&1 && .venv/bin/python -m pip --version >/dev/null 2>&1; then
    return 0
  fi
  rm -rf .venv
  return 1
}

if [[ "${1:-}" == "--python" ]]; then
  [[ -n "${2:-}" ]] || die "--python needs a path"
  command -v "${2}" >/dev/null 2>&1 || die "not executable: ${2}"
  CANDIDATES=("${2}")
else
  CANDIDATES=(python3.13 python3.12 python3.11 python3.10)
fi

say "Probing for a supported interpreter (3.10-3.13, prefer 3.13)"
FOUND=()
for c in "${CANDIDATES[@]}"; do
  if command -v "$c" >/dev/null 2>&1; then
    if in_range "$(command -v "$c")"; then
      FOUND+=("$(command -v "$c")")
    else
      printf '    found %s but it is outside 3.10-3.13, skipping\n' "$c"
    fi
  fi
done
if command -v python3 >/dev/null 2>&1 && in_range "$(command -v python3)"; then
  P3="$(command -v python3)"
  SKIP=0
  for f in ${FOUND[@]+"${FOUND[@]}"}; do
    if [[ "$f" == "$P3" ]]; then SKIP=1; fi
  done
  if [[ "$SKIP" -eq 0 ]]; then FOUND+=("$P3"); fi
fi
if [[ "${#FOUND[@]}" -eq 0 ]]; then
  die "no supported interpreter found (need 3.10-3.13, recommend 3.13).
On macOS without Homebrew, install the python.org 'macOS 64-bit universal2' installer:
  https://www.python.org/downloads/macos/   (latest 3.13.x)
then re-run:
  ./scripts/bootstrap_env.sh --python /Library/Frameworks/Python3.framework/Versions/3.13/bin/python3.13"
fi

# An existing .venv is reused only if it is supported AND has a working pip
if [[ -d .venv ]] && .venv/bin/python -c "$RANGE_CHECK" >/dev/null 2>&1 \
   && .venv/bin/python -m pip --version >/dev/null 2>&1; then
  ok ".venv already exists on a supported interpreter - reusing ($(.venv/bin/python -V 2>&1))"
  exit 0
fi
if [[ -d .venv ]]; then
  ok ".venv exists but is broken or unsupported - recreating it"
  rm -rf .venv
fi

PY=""
for p in "${FOUND[@]}"; do
  if try_venv "$p"; then
    PY="$p"
    break
  fi
  printf '    venv creation failed for %s (missing ensurepip? Debian/Ubuntu: sudo apt install python3-venv) - trying next candidate\n' "$p"
done
[[ -n "$PY" ]] || die "could not create a working .venv with any candidate interpreter.
If every candidate reports missing ensurepip: Debian/Ubuntu -> sudo apt install python3-venv;
macOS -> reinstall the python.org 3.13 universal2 installer, then re-run this script."

ok "interpreter: ${PY} ($("${PY}" -V 2>&1))"
ok "created .venv ($(.venv/bin/python -V 2>&1), pip $(.venv/bin/python -m pip --version | awk '{print $2}'))"
echo "next:"
echo "  source .venv/bin/activate"
if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "x86_64" ]]; then
  echo "  source ~/.qff26-openssl-env.sh    # Intel macOS: static OpenSSL for the cryptography sdist build"
fi
echo "  pip install -r requirements.txt"
echo "  python common/env_check.py"
