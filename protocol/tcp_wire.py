"""Synchronous TCP transport for QFF PS-P1 serialized protocol frames.

Wire format:
    4-byte unsigned big-endian frame length
    frame_length bytes of serialized QFF protocol data

TCP is a byte stream, so recv_frame() reads the complete header and body.
This module does not implement cryptography; framing is handled here and
authentication/encryption remain the responsibility of protocol.channels.
"""

from __future__ import annotations

import socket

DEFAULT_MAX_FRAME_SIZE = 16 * 1024 * 1024
HEADER_SIZE = 4
MAX_LENGTH_FIELD = (1 << 32) - 1


class TransportError(ConnectionError):
    """Invalid or incomplete TCP frame."""


class SocketEndpoint:
    """Socket-backed endpoint implementing the BaseChannel endpoint interface.

    send() transmits one complete length-prefixed frame.
    recv_frame() returns one complete frame, or None on clean EOF before
    the beginning of a new frame.

    Use one reader per connection. The demo uses synchronous I/O and does
    not require reader threads.
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        name: str = "tcp",
        max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
    ) -> None:
        if not isinstance(max_frame_size, int):
            raise TypeError("max_frame_size must be an integer")
        if not 1 <= max_frame_size <= MAX_LENGTH_FIELD:
            raise ValueError("max_frame_size must be between 1 and 2^32-1")

        self.socket = sock
        self.name = name
        self.max_frame_size = max_frame_size

    def send(self, frame: bytes) -> None:
        """Send one serialized frame using a four-byte length prefix."""
        if not isinstance(frame, bytes):
            raise TypeError("frame must be bytes")
        if not frame:
            raise TransportError("empty frames are not permitted")
        if len(frame) > self.max_frame_size:
            raise TransportError(
                f"frame size {len(frame)} exceeds limit {self.max_frame_size}"
            )

        header = len(frame).to_bytes(HEADER_SIZE, byteorder="big")
        self.socket.sendall(header + frame)

    def recv_frame(self) -> bytes | None:
        """Receive one complete frame; return None on clean connection EOF."""
        header = self._recv_exact(HEADER_SIZE, allow_clean_eof=True)

        if header is None:
            return None

        frame_length = int.from_bytes(header, byteorder="big")

        if frame_length == 0:
            raise TransportError("zero-length frames are not permitted")

        if frame_length > self.max_frame_size:
            raise TransportError(
                f"received frame size {frame_length} exceeds limit "
                f"{self.max_frame_size}"
            )

        frame = self._recv_exact(frame_length, allow_clean_eof=False)
        if frame is None:
            raise TransportError("unexpected EOF while reading frame body")

        return frame

    def _recv_exact(
        self,
        size: int,
        *,
        allow_clean_eof: bool,
    ) -> bytes | None:
        """Read exactly size bytes, handling arbitrary TCP fragmentation."""
        received = bytearray()

        while len(received) < size:
            chunk = self.socket.recv(size - len(received))

            if not chunk:
                if allow_clean_eof and not received:
                    return None

                raise TransportError(
                    f"connection closed mid-frame: received "
                    f"{len(received)} of {size} bytes"
                )

            received.extend(chunk)

        return bytes(received)
