"""Verify SHA256SUMS.txt after extracting the agent kit."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SHA256SUMS.txt"


def main() -> int:
    if not MANIFEST.exists():
        print("SHA256SUMS.txt is missing", file=sys.stderr)
        return 2
    failed = 0
    checked = 0
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            expected, relpath = line.split("  ", 1)
        except ValueError:
            print(f"Malformed checksum line: {line}", file=sys.stderr)
            failed += 1
            continue
        path = (ROOT / relpath).resolve()
        if ROOT.resolve() not in path.parents:
            print(f"Refusing path outside project root: {relpath}", file=sys.stderr)
            failed += 1
            continue
        if not path.is_file():
            print(f"MISSING {relpath}")
            failed += 1
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checked += 1
        if digest != expected:
            print(f"MISMATCH {relpath}")
            failed += 1
        else:
            print(f"OK {relpath}")
    print(f"Checked {checked} files; failures={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
