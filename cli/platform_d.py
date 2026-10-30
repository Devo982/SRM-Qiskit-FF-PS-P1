"""Two-device Platform D TCP experiment for QFF PS-P1.

Run Bob on the second device:
  python -m cli.platform_d --role server --suite QFF26-PQC-1 --run-id D_20261030_WIFI01 --bind-host 0.0.0.0

Run Alice on the first device:
  python -m cli.platform_d --role client --suite QFF26-PQC-1 --run-id D_20261030_WIFI01 --host <BOB_LAN_IP>

The experiment measures TCP connect time, handshake elapsed time, and
application round-trip time/goodput over real TCP. It does not change the
protocol or its cryptographic state machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import statistics
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cli.adapter import SecureChannelFacade  # noqa: E402
from protocol.suites import SUITES  # noqa: E402
from protocol.tcp_wire import DEFAULT_MAX_FRAME_SIZE, SocketEndpoint, TransportError  # noqa: E402

RECORD_OVERHEAD_BYTES = 32  # 16-byte record header + 16-byte GCM tag
MAX_PAYLOAD_BYTES = DEFAULT_MAX_FRAME_SIZE - RECORD_OVERHEAD_BYTES
DEFAULT_PAYLOAD_SIZES = (1024, 102400, 10485760)
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def parse_payload_sizes(value: str) -> tuple[int, ...]:
    """Parse unique positive payload sizes bounded by the TCP frame limit."""
    try:
        values = tuple(int(part.strip()) for part in value.split(","))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("payload sizes must be comma-separated integers") from exc
    if not values or any(size <= 0 for size in values):
        raise argparse.ArgumentTypeError("payload sizes must all be positive")
    if len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("payload sizes must not contain duplicates")
    if any(size > MAX_PAYLOAD_BYTES for size in values):
        raise argparse.ArgumentTypeError(
            f"payload size exceeds transport maximum ({MAX_PAYLOAD_BYTES} bytes)"
        )
    return values


def make_payload(size: int, run_id: str, suite_id: str, session: int, round_index: int) -> bytes:
    """Create deterministic, non-secret test bytes for repeatable integrity checks."""
    seed = f"QFF26-Platform-D|{run_id}|{suite_id}|{session}|{size}|{round_index}".encode()
    return hashlib.shake_256(seed).digest(size)


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile from no samples")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def summarize(values: list[float], unit: str) -> dict[str, float | int | str]:
    if not values:
        raise ValueError("cannot summarize an empty sample set")
    return {
        "unit": unit,
        "n": len(values),
        "min": round(min(values), 4),
        "median": round(statistics.median(values), 4),
        "p95": round(percentile(values, 0.95), 4),
        "max": round(max(values), 4),
    }


def environment_snapshot() -> dict[str, Any]:
    """Capture host metadata without recording IP addresses or key material."""
    try:
        import psutil
        physical_cores = psutil.cpu_count(logical=False)
        logical_cores = psutil.cpu_count(logical=True)
        ram_total_gb = round(psutil.virtual_memory().total / (1024 ** 3), 3)
        battery = psutil.sensors_battery()
        on_battery = (not battery.power_plugged) if battery and battery.power_plugged is not None else None
    except Exception:  # metadata failure must not prevent a network test
        physical_cores = None
        logical_cores = os.cpu_count()
        ram_total_gb = None
        on_battery = None

    versions: dict[str, str | None] = {}
    for distribution in ("cryptography", "psutil"):
        try:
            versions[distribution] = package_version(distribution)
        except PackageNotFoundError:
            versions[distribution] = None

    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "physical_cores": physical_cores,
        "logical_cores": logical_cores,
        "ram_total_gb": ram_total_gb,
        "on_battery": on_battery,
        "python": platform.python_version(),
        "packages": versions,
    }


def _identity_paths(role: str) -> tuple[Path, Path, str]:
    identity_name = "alice" if role == "client" else "bob"
    identity = "client:alice" if role == "client" else "server:bob"
    identities_dir = REPO_ROOT / "identities"
    private_identity = identities_dir / f"{identity_name}.json"
    trust_store = identities_dir / "trust_store.test.json"
    missing = [str(path.relative_to(REPO_ROOT)) for path in (private_identity, trust_store) if not path.is_file()]
    if missing:
        raise RuntimeError(
            "required Platform D test material is missing: " + ", ".join(missing)
            + ". Create a matching test trust store on the provisioning machine; "
            "securely transfer only this role's private identity file and the shared public test trust store."
        )
    return identities_dir, trust_store, identity


def make_facade(role: str, suite_id: str, endpoint: SocketEndpoint) -> SecureChannelFacade:
    identities_dir, trust_store, identity = _identity_paths(role)
    facade = SecureChannelFacade(
        role,
        identity,
        suite_id,
        trust_store_path=trust_store,
        identities_dir=identities_dir,
    )
    return facade.open(endpoint)


def receive_and_deliver(endpoint: SocketEndpoint, facade: SecureChannelFacade, description: str) -> int:
    frame = endpoint.recv_frame()
    if frame is None:
        raise TransportError(f"peer disconnected while waiting for {description}")
    facade.accept_frame(frame)
    if facade.state == "FAILED":
        raise RuntimeError(
            f"{description} rejected by secure channel (failure category: {facade.failure_category})"
        )
    return len(frame)


def require_state(facade: SecureChannelFacade, expected: str, description: str) -> None:
    if facade.state != expected:
        raise RuntimeError(
            f"{description}: expected state {expected}, got {facade.state} "
            f"(failure category: {facade.failure_category})"
        )


def result_path(args: argparse.Namespace, role: str) -> Path:
    suite_slug = args.suite.replace("/", "_")
    return args.output_dir / f"{args.run_id}_{suite_slug}_{role}.json"


def write_result(args: argparse.Namespace, role: str, content: dict[str, Any]) -> Path:
    path = result_path(args, role)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[{role}] metrics written: {path}", flush=True)
    return path


def summarize_client_samples(samples: list[dict[str, Any]], payload_sizes: tuple[int, ...]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for size in payload_sizes:
        selected = [sample for sample in samples if sample["payload_bytes_each_direction"] == size]
        rtts = [float(sample["round_trip_ms"]) for sample in selected]
        rates = [float(sample["round_trip_goodput_mib_s"]) for sample in selected]
        summaries.append({
            "payload_bytes_each_direction": size,
            "round_trip_ms": summarize(rtts, "ms"),
            "round_trip_goodput_mib_s": summarize(rates, "MiB/s"),
        })
    return summaries


def run_server(args: argparse.Namespace) -> dict[str, Any]:
    handshake_samples: list[float] = []
    session_durations: list[float] = []
    verified_records = 0
    received_payload_bytes = 0
    sent_payload_bytes = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(args.timeout)
        listener.bind((args.bind_host, args.port))
        listener.listen(args.sessions)
        print(
            f"[server] listening on {args.bind_host}:{args.port}; "
            f"suite={args.suite}; sessions={args.sessions}",
            flush=True,
        )

        for session_index in range(args.sessions):
            conn, peer_address = listener.accept()
            with conn:
                conn.settimeout(args.timeout)
                endpoint = SocketEndpoint(conn, name="platform-d-bob")
                session_start = time.perf_counter()
                handshake_start = time.perf_counter()
                server = make_facade("server", args.suite, endpoint)

                receive_and_deliver(endpoint, server, "client M1")
                require_state(server, "M2_SENT", "server after M1")
                receive_and_deliver(endpoint, server, "client M3")
                require_state(server, "ESTABLISHED", "server after M3")
                handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
                handshake_samples.append(handshake_ms)
                print(
                    f"[server] session {session_index + 1}/{args.sessions} "
                    f"from {peer_address[0]} established; server_handshake={handshake_ms:.3f} ms",
                    flush=True,
                )

                for payload_size in args.payload_sizes:
                    for round_index in range(args.rounds):
                        expected = make_payload(
                            payload_size, args.run_id, args.suite, session_index, round_index
                        )
                        receive_and_deliver(endpoint, server, "client application record")
                        received = server.recv()
                        if received != expected:
                            raise RuntimeError(
                                f"payload mismatch: session={session_index + 1}, "
                                f"size={payload_size}, round={round_index + 1}"
                            )
                        verified_records += 1
                        received_payload_bytes += len(received)
                        server.send(received)
                        sent_payload_bytes += len(received)

                receive_and_deliver(endpoint, server, "client authenticated close")
                require_state(server, "CLOSED", "server after authenticated close")
                session_durations.append((time.perf_counter() - session_start) * 1000.0)
                print(
                    f"[server] session {session_index + 1}/{args.sessions} complete; "
                    "all application records matched; authenticated close received",
                    flush=True,
                )

    return {
        "schema_version": 1,
        "platform_label": "D",
        "experiment": "two-device real-link TCP secure-channel experiment",
        "run_id": args.run_id,
        "suite": args.suite,
        "role": "server",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment_snapshot(),
        "configuration": {
            "sessions": args.sessions,
            "rounds_per_payload": args.rounds,
            "payload_sizes_bytes": list(args.payload_sizes),
            "port": args.port,
            "transport": "TCP",
        },
        "summary": {
            "successful_sessions": len(handshake_samples),
            "server_handshake_ms": summarize(handshake_samples, "ms"),
            "server_session_duration_ms": summarize(session_durations, "ms"),
            "verified_application_records": verified_records,
            "received_plaintext_bytes": received_payload_bytes,
            "sent_plaintext_bytes": sent_payload_bytes,
        },
        "raw_server_handshake_ms": handshake_samples,
        "raw_server_session_duration_ms": session_durations,
    }


def run_client(args: argparse.Namespace) -> dict[str, Any]:
    connect_samples: list[float] = []
    handshake_samples: list[float] = []
    session_durations: list[float] = []
    app_samples: list[dict[str, Any]] = []

    for session_index in range(args.sessions):
        session_start = time.perf_counter()
        connect_start = time.perf_counter()
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as conn:
            connect_ms = (time.perf_counter() - connect_start) * 1000.0
            connect_samples.append(connect_ms)
            conn.settimeout(args.timeout)
            endpoint = SocketEndpoint(conn, name="platform-d-alice")

            handshake_start = time.perf_counter()
            client = make_facade("client", args.suite, endpoint)
            require_state(client, "M1_SENT", "client after M1")
            receive_and_deliver(endpoint, client, "server M2")
            require_state(client, "ESTABLISHED", "client after M2")
            handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
            handshake_samples.append(handshake_ms)
            print(
                f"[client] session {session_index + 1}/{args.sessions} established; "
                f"tcp_connect={connect_ms:.3f} ms; client_handshake={handshake_ms:.3f} ms",
                flush=True,
            )

            for payload_size in args.payload_sizes:
                for round_index in range(args.rounds):
                    payload = make_payload(
                        payload_size, args.run_id, args.suite, session_index, round_index
                    )
                    started = time.perf_counter()
                    client.send(payload)
                    receive_and_deliver(endpoint, client, "server application echo")
                    received = client.recv()
                    elapsed_ms = (time.perf_counter() - started) * 1000.0
                    if received != payload:
                        raise RuntimeError(
                            f"echo mismatch: session={session_index + 1}, "
                            f"size={payload_size}, round={round_index + 1}"
                        )
                    bidirectional_mib = (2 * payload_size) / (1024 ** 2)
                    goodput = bidirectional_mib / (elapsed_ms / 1000.0)
                    app_samples.append({
                        "session": session_index + 1,
                        "payload_bytes_each_direction": payload_size,
                        "round": round_index + 1,
                        "round_trip_ms": round(elapsed_ms, 4),
                        "round_trip_goodput_mib_s": round(goodput, 4),
                    })

            client.close()
            require_state(client, "CLOSED", "client after authenticated close")
        session_durations.append((time.perf_counter() - session_start) * 1000.0)
        print(
            f"[client] session {session_index + 1}/{args.sessions} complete; "
            "all echoed records matched; authenticated close sent",
            flush=True,
        )

    return {
        "schema_version": 1,
        "platform_label": "D",
        "experiment": "two-device real-link TCP secure-channel experiment",
        "run_id": args.run_id,
        "suite": args.suite,
        "role": "client",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment_snapshot(),
        "configuration": {
            "sessions": args.sessions,
            "rounds_per_payload": args.rounds,
            "payload_sizes_bytes": list(args.payload_sizes),
            "port": args.port,
            "transport": "TCP",
        },
        "summary": {
            "successful_sessions": len(handshake_samples),
            "tcp_connect_ms": summarize(connect_samples, "ms"),
            "client_handshake_ms": summarize(handshake_samples, "ms"),
            "session_duration_ms": summarize(session_durations, "ms"),
            "application_by_payload": summarize_client_samples(app_samples, args.payload_sizes),
        },
        "raw_tcp_connect_ms": connect_samples,
        "raw_client_handshake_ms": handshake_samples,
        "raw_session_duration_ms": session_durations,
        "raw_application_samples": app_samples,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("server", "client"))
    parser.add_argument("--suite", required=True, choices=sorted(SUITES))
    parser.add_argument("--run-id", required=True, help="shared ID used on both devices")
    parser.add_argument("--host", help="server LAN IP/hostname; required for client")
    parser.add_argument("--bind-host", default="0.0.0.0", help="server bind address")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument(
        "--payload-sizes",
        type=parse_payload_sizes,
        default=DEFAULT_PAYLOAD_SIZES,
        help="comma-separated plaintext bytes (default: 1024,102400,10485760)",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "results" / "platform_d")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        parser.error("run-id must contain only letters, digits, dot, underscore or hyphen (max 64 chars)")
    if args.role == "client" and not args.host:
        parser.error("--host is required for --role client")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not 1 <= args.sessions <= 100:
        parser.error("sessions must be between 1 and 100")
    if not 1 <= args.rounds <= 100:
        parser.error("rounds must be between 1 and 100")
    if args.timeout <= 0:
        parser.error("timeout must be positive")

    try:
        if args.role == "server":
            content = run_server(args)
        else:
            content = run_client(args)
        path = write_result(args, args.role, content)
        summary = content["summary"]
        if args.role == "client":
            print(f"[client] successful sessions: {summary['successful_sessions']}/{args.sessions}")
            print(f"[client] TCP connect median: {summary['tcp_connect_ms']['median']} ms")
            print(f"[client] handshake median: {summary['client_handshake_ms']['median']} ms")
            for item in summary["application_by_payload"]:
                print(
                    f"[client] {item['payload_bytes_each_direction']} B each way: "
                    f"RTT median={item['round_trip_ms']['median']} ms; "
                    f"round-trip goodput median={item['round_trip_goodput_mib_s']['median']} MiB/s"
                )
        else:
            print(f"[server] successful sessions: {summary['successful_sessions']}/{args.sessions}")
            print(f"[server] verified application records: {summary['verified_application_records']}")
        print(f"[platform-d] result file: {path}", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, TransportError) as exc:
        print(f"[platform-d] ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
