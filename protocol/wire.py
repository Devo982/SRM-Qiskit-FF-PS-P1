"""In-memory wire + synchronous pump.

Endpoints exchange serialized frames through this object; every fault in the
T1-T9 battery is injected HERE, on the bytes between two real endpoints, so
every fault travels the real parse/verify path (design v2 section 7).
"""
from __future__ import annotations

from .channels import BaseChannel, Endpoint


class InMemoryWire:
    """Bidirectional frame pipe with fault-injection hooks.

    Frame indices count per direction across the whole session (handshake
    frames included): c2s #0 = M1, c2s #1 = M3, c2s #2+ = app records;
    s2c #0 = M2, s2c #1+ = app records.
    """

    def __init__(self) -> None:
        self.client_ep = Endpoint("client")
        self.server_ep = Endpoint("server")
        self._faults: dict[str, list[tuple[int, object]]] = {"c2s": [], "s2c": []}
        self._counts = {"c2s": 0, "s2c": 0}
        # delivery log: (direction, frame_index, frame) — used by tests to
        # capture genuine frames for replay/splice scenarios (T7b, T8b, T8c)
        self.log: list[tuple[str, int, bytes]] = []

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def add_fault(self, direction: str, frame_index: int, fn) -> None:
        """Register a fault fn(frame)->frame | list[frame] for one frame index."""
        if direction not in self._faults:
            raise ValueError("direction must be 'c2s' or 's2c'")
        self._faults[direction].append((frame_index, fn))

    def _deliver(self, direction: str, from_ep: Endpoint, to_channel: BaseChannel) -> int:
        delivered = 0
        while from_ep.outbox:
            frame = from_ep.outbox.pop(0)
            idx = self._counts[direction]
            self._counts[direction] = idx + 1
            for fi, fn in self._faults[direction]:
                if fi == idx:
                    frame = fn(frame)
            frames = frame if isinstance(frame, (list, tuple)) else [frame]
            for f in frames:
                self.log.append((direction, idx, f))
                to_channel.on_frame(f)
            delivered += 1
        return delivered

    def pump(self, client: BaseChannel, server: BaseChannel, max_rounds: int = 16) -> int:
        """Deliver every queued frame both ways until queues stay empty."""
        total = 0
        for _ in range(max_rounds):
            moved = self._deliver("c2s", self.client_ep, server)
            moved += self._deliver("s2c", self.server_ep, client)
            total += moved
            if moved == 0:
                break
        return total

