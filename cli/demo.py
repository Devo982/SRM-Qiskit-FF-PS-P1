"""End-to-end demo: python -m cli.demo --suite QFF26-PQC-1

Runs both endpoints in-process over the in-memory wire and prints METADATA
ONLY output (states, sizes, suite id, failure categories) - invariant I4:
never keys, never plaintext of failed records.

Requires provisioning: python scripts/provision_identities.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cli.adapter import SecureChannelFacade  # noqa: E402
from protocol.suites import SUITES  # noqa: E402
from protocol.wire import InMemoryWire  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="QFF26-PQC-1", choices=sorted(SUITES))
    args = parser.parse_args()

    if not (REPO_ROOT / "trust_store.json").exists():
        sys.exit("trust store missing - run: python scripts/provision_identities.py")

    wire = InMemoryWire()
    client = SecureChannelFacade("client", "client:alice", args.suite).open(wire.client_ep)
    server = SecureChannelFacade("server", "server:bob", args.suite).open(wire.server_ep)
    print(f"[demo] suite={args.suite} (local policy, no online negotiation)")

    def pump() -> None:
        wire.pump(client._channel, server._channel)  # façade-internal plumbing

    pump()
    print(f"[demo] client state={client.state} | server state={server.state}")
    if not client.established:
        sys.exit(f"[demo] handshake failed: {client.failure_category}: "
                 f"{client._channel.failure_detail}")

    message = b"Hello from Alice - post-quantum channel is live."
    client.send(message)
    pump()
    received = server.recv()
    print(f"[demo] c2s: sent {len(message)} B, received {len(received)} B, "
          f"match={received == message}")

    reply = b"Hello from Bob - authenticated and encrypted both ways."
    server.send(reply)
    pump()
    got_reply = client.recv()
    print(f"[demo] s2c: sent {len(reply)} B, received {len(got_reply)} B, "
          f"match={got_reply == reply}")

    client.close()
    pump()
    print(f"[demo] authenticated close -> client={client.state}, server={server.state}")
    print(f"[demo] exporter label available for audit: {len(client._channel.exporter)} B "
          "(value never displayed)")


if __name__ == "__main__":
    main()

