"""Two-process TCP demonstration of the QFF PS-P1 secure channel.

Start the server in one terminal:
    python -m cli.tcp_demo --role server --suite QFF26-PQC-1

Start the client in another terminal:
    python -m cli.tcp_demo --role client --suite QFF26-PQC-1

Default binding is 127.0.0.1:8765.

The TCP transport carries length-prefixed frames. Authentication,
key establishment and application-record encryption are performed
by the existing protocol implementation.
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cli.adapter import SecureChannelFacade  # noqa: E402
from protocol.suites import SUITES  # noqa: E402
from protocol.tcp_wire import SocketEndpoint, TransportError  # noqa: E402


ALICE_MESSAGE = b"Hello from Alice - post-quantum channel is live."
BOB_REPLY = b"Hello from Bob - authenticated and encrypted both ways."

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_TIMEOUT = 30.0


def _check_local_test_material() -> tuple[Path, Path]:
    identities_dir = REPO_ROOT / "identities"
    trust_path = identities_dir / "trust_store.test.json"

    required = (
        identities_dir / "alice.json",
        identities_dir / "bob.json",
        trust_path,
    )

    missing = [str(path.relative_to(REPO_ROOT)) for path in required if not path.is_file()]

    if missing:
        raise RuntimeError(
            "local test identity material is missing: "
            + ", ".join(missing)
            + ". Run: python scripts/provision_identities.py"
        )

    return identities_dir, trust_path


def _make_facade(
    role: str,
    suite_id: str,
    endpoint: SocketEndpoint,
) -> SecureChannelFacade:
    identities_dir, trust_path = _check_local_test_material()

    facade = SecureChannelFacade(
        role,
        "client:alice" if role == "client" else "server:bob",
        suite_id,
        trust_store_path=trust_path,
        identities_dir=identities_dir,
    )

    return facade.open(endpoint)


def _receive_and_deliver(
    endpoint: SocketEndpoint,
    facade: SecureChannelFacade,
    description: str,
) -> int:
    """Read one transport frame and give it to the existing channel."""
    frame = endpoint.recv_frame()

    if frame is None:
        raise TransportError(f"peer disconnected while waiting for {description}")

    facade.accept_frame(frame)

    if facade.state == "FAILED":
        raise RuntimeError(
            f"{description} rejected by secure channel "
            f"(failure category: {facade.failure_category})"
        )

    return len(frame)


def _require_state(
    facade: SecureChannelFacade,
    expected: str,
    description: str,
) -> None:
    if facade.state != expected:
        raise RuntimeError(
            f"{description}: expected state {expected}, got {facade.state} "
            f"(failure category: {facade.failure_category})"
        )


def run_server(args: argparse.Namespace) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(args.timeout)
        listener.bind((args.host, args.port))
        listener.listen(1)

        print(
            f"[server] listening on {args.host}:{args.port}; "
            f"suite={args.suite}",
            flush=True,
        )

        conn, address = listener.accept()

        with conn:
            conn.settimeout(args.timeout)
            print(f"[server] TCP connection accepted from {address[0]}", flush=True)

            endpoint = SocketEndpoint(conn, name="bob-tcp")
            server = _make_facade("server", args.suite, endpoint)

            _receive_and_deliver(endpoint, server, "client M1")
            _require_state(server, "M2_SENT", "server after M1")

            # M2 is sent by the existing ServerChannel via endpoint.send().
            _receive_and_deliver(endpoint, server, "client M3")
            _require_state(server, "ESTABLISHED", "server after M3")

            print(
                f"[server] mutual handshake complete; state={server.state}",
                flush=True,
            )

            # Receive Alice's encrypted application record.
            _receive_and_deliver(endpoint, server, "Alice application record")
            received = server.recv()

            if received != ALICE_MESSAGE:
                raise RuntimeError("Alice application payload did not match")

            print(
                f"[server] c2s application record: "
                f"bytes={len(received)}, match=True",
                flush=True,
            )

            # Send Bob's encrypted reply.
            server.send(BOB_REPLY)

            print(
                f"[server] s2c reply sent: bytes={len(BOB_REPLY)}",
                flush=True,
            )

            # Alice sends an authenticated close record.
            _receive_and_deliver(endpoint, server, "Alice authenticated close")
            _require_state(server, "CLOSED", "server after authenticated close")

            print(
                f"[server] authenticated close received; state={server.state}",
                flush=True,
            )


def run_client(args: argparse.Namespace) -> None:
    with socket.create_connection(
        (args.host, args.port),
        timeout=args.timeout,
    ) as conn:
        conn.settimeout(args.timeout)

        endpoint = SocketEndpoint(conn, name="alice-tcp")
        client = _make_facade("client", args.suite, endpoint)

        _require_state(client, "M1_SENT", "client after starting handshake")

        # Receive M2; processing it sends M3 and establishes the client side.
        _receive_and_deliver(endpoint, client, "server M2")
        _require_state(client, "ESTABLISHED", "client after M2")

        print(
            f"[client] mutual handshake complete; state={client.state}",
            flush=True,
        )

        # Send Alice's encrypted application record.
        client.send(ALICE_MESSAGE)

        print(
            f"[client] c2s application record sent: bytes={len(ALICE_MESSAGE)}",
            flush=True,
        )

        # Receive and verify Bob's encrypted reply.
        _receive_and_deliver(endpoint, client, "Bob application reply")
        received = client.recv()

        if received != BOB_REPLY:
            raise RuntimeError("Bob application reply did not match")

        print(
            f"[client] s2c application record: "
            f"bytes={len(received)}, match=True",
            flush=True,
        )

        # Send authenticated close. The server confirms receipt in its output.
        client.close()
        _require_state(client, "CLOSED", "client after close")

        print(
            f"[client] authenticated close record sent; state={client.state}",
            flush=True,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--role",
        required=True,
        choices=("server", "client"),
        help="run as Bob/server or Alice/client",
    )
    parser.add_argument(
        "--suite",
        default="QFF26-PQC-1",
        choices=sorted(SUITES),
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)

    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not 1 <= args.port <= 65535:
        print("ERROR: port must be between 1 and 65535", file=sys.stderr)
        return 2

    if args.timeout <= 0:
        print("ERROR: timeout must be positive", file=sys.stderr)
        return 2

    try:
        if args.role == "server":
            run_server(args)
        else:
            run_client(args)

    except (OSError, RuntimeError, TransportError) as exc:
        print(
            f"[tcp-demo] ERROR: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
