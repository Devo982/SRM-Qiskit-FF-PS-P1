#!/usr/bin/env python3
"""Capture real-link ICMP RTT and packet-loss evidence for Platform D."""
from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def parse_ping_output(output: str) -> dict[str, float | int | None]:
    """Parse macOS, Linux, or Windows ping summaries; preserve missing RTT as None."""
    packet_match = re.search(
        r"(?P<sent>\d+)\s+packets transmitted,\s*"
        r"(?P<received>\d+)\s+(?:packets\s+)?received,\s*"
        r"(?P<loss>[\d.]+)% packet loss",
        output,
        re.IGNORECASE,
    )
    if packet_match:
        sent = int(packet_match.group("sent"))
        received = int(packet_match.group("received"))
        loss = float(packet_match.group("loss"))
    else:
        windows_match = re.search(
            r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*"
            r"Lost\s*=\s*(\d+)\s*\(([\d.]+)%\s*loss\)",
            output,
            re.IGNORECASE,
        )
        if not windows_match:
            raise ValueError("could not parse packet counts/loss from ping output")
        sent = int(windows_match.group(1))
        received = int(windows_match.group(2))
        loss = float(windows_match.group(4))

    rtt_match = re.search(
        r"(?:round-trip|rtt)\s+min/avg/max/(?:stddev|mdev)\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    if rtt_match:
        rtt_min, rtt_avg, rtt_max, rtt_spread = (float(rtt_match.group(i)) for i in range(1, 5))
    else:
        windows_rtt = re.search(
            r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
            output,
            re.IGNORECASE,
        )
        if windows_rtt:
            rtt_min = float(windows_rtt.group(1))
            rtt_max = float(windows_rtt.group(2))
            rtt_avg = float(windows_rtt.group(3))
            rtt_spread = None
        else:
            rtt_min = rtt_avg = rtt_max = rtt_spread = None

    return {
        "packets_sent": sent,
        "packets_received": received,
        "packet_loss_pct": loss,
        "rtt_min_ms": rtt_min,
        "rtt_avg_ms": rtt_avg,
        "rtt_max_ms": rtt_max,
        "rtt_stddev_or_mdev_ms": rtt_spread,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", required=True, help="other device's LAN IP or hostname")
    parser.add_argument("--direction", required=True, choices=("alice_to_bob", "bob_to_alice"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results" / "platform_d")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        parser.error("run-id must contain only letters, digits, dot, underscore or hyphen")
    if not 5 <= args.count <= 1000:
        parser.error("count must be between 5 and 1000")

    if platform.system() == "Windows":
        command = ["ping", "-n", str(args.count), "-w", "1000", args.peer]
    else:
        command = ["ping", "-c", str(args.count), "-i", "1", args.peer]

    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.count * 3 + 20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[platform-d-probe] ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    output = completed.stdout or ""
    try:
        metrics = parse_ping_output(output)
    except ValueError as exc:
        print(output, end="" if output.endswith("\n") else "\n")
        print(f"[platform-d-probe] ERROR: {exc}; ICMP may be blocked or ping output unsupported.", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{args.run_id}_{args.direction}_ping"
    raw_path = args.output_dir / f"{stem}.txt"
    json_path = args.output_dir / f"{stem}.json"
    raw_path.write_text(output, encoding="utf-8")
    result: dict[str, Any] = {
        "schema_version": 1,
        "platform_label": "D",
        "run_id": args.run_id,
        "direction": args.direction,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "local_hostname": socket.gethostname(),
        "local_os": platform.platform(),
        "peer_address_recorded": False,
        "probe": "ICMP echo via system ping",
        "requested_packet_count": args.count,
        "ping_exit_code": completed.returncode,
        "metrics": metrics,
        "raw_output_file": raw_path.name,
    }
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[platform-d-probe] direction={args.direction}; packets={metrics['packets_received']}/{metrics['packets_sent']}; loss={metrics['packet_loss_pct']}%")
    print(
        "[platform-d-probe] RTT min/avg/max="
        f"{metrics['rtt_min_ms']}/{metrics['rtt_avg_ms']}/{metrics['rtt_max_ms']} ms"
    )
    print(f"[platform-d-probe] JSON: {json_path}")
    print(f"[platform-d-probe] raw ping: {raw_path}")
    if metrics["packets_received"] == 0:
        print("[platform-d-probe] WARNING: no ICMP replies; TCP may still work if ICMP is filtered.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
