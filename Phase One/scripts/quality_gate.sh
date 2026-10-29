#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p results/logs
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

run_gate() {
  local name="$1"
  shift
  local log="results/logs/${STAMP}_${name}.log"
  echo "== ${name}: $* =="
  set +e
  "$@" 2>&1 | tee "$log"
  local status=${PIPESTATUS[0]}
  set -e
  echo "exit_code=${status}" | tee -a "$log"
  if [[ "$status" -ne 0 ]]; then
    echo "GATE FAILED: ${name}; inspect ${log}" >&2
    exit "$status"
  fi
}

run_gate preflight python -m src.cli check
run_gate pytest python -m pytest -q
run_gate handshake_all python -m src.cli handshake --mode all

echo "All correctness gates passed. This script does not run the long benchmark; use the documented benchmark commands after the gates."
