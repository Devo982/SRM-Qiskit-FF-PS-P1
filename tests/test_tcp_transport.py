"""Tests for the QFF PS-P1 TCP length-prefixed transport."""

from __future__ import annotations

import socket
import unittest

from protocol.tcp_wire import (
    DEFAULT_MAX_FRAME_SIZE,
    HEADER_SIZE,
    SocketEndpoint,
    TransportError,
)


def encode_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(HEADER_SIZE, "big") + payload


class FragmentedSocket:
    """Deterministic socket substitute that returns small chunks."""

    def __init__(self, incoming: bytes = b"", chunk_size: int = 2):
        self.incoming = bytearray(incoming)
        self.chunk_size = chunk_size
        self.sent = bytearray()

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            return b""

        count = min(size, self.chunk_size, len(self.incoming))
        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


class TcpTransportTests(unittest.TestCase):

    def test_send_adds_four_byte_big_endian_length(self):
        sock = FragmentedSocket()
        endpoint = SocketEndpoint(sock)

        endpoint.send(b"QFF")

        self.assertEqual(sock.sent, b"\x00\x00\x00\x03QFF")

    def test_receives_fragmented_header_and_body(self):
        payload = b"fragmented TCP frame"
        sock = FragmentedSocket(encode_frame(payload), chunk_size=1)
        endpoint = SocketEndpoint(sock)

        self.assertEqual(endpoint.recv_frame(), payload)

    def test_receives_multiple_frames_from_one_stream(self):
        first = b"first"
        second = b"second"
        sock = FragmentedSocket(
            encode_frame(first) + encode_frame(second),
            chunk_size=3,
        )
        endpoint = SocketEndpoint(sock)

        self.assertEqual(endpoint.recv_frame(), first)
        self.assertEqual(endpoint.recv_frame(), second)
        self.assertIsNone(endpoint.recv_frame())

    def test_clean_eof_before_new_frame(self):
        endpoint = SocketEndpoint(FragmentedSocket())
        self.assertIsNone(endpoint.recv_frame())

    def test_rejects_partial_header(self):
        endpoint = SocketEndpoint(FragmentedSocket(b"\x00\x00"))

        with self.assertRaises(TransportError):
            endpoint.recv_frame()

    def test_rejects_partial_body(self):
        incomplete = (4).to_bytes(4, "big") + b"xy"
        endpoint = SocketEndpoint(FragmentedSocket(incomplete))

        with self.assertRaises(TransportError):
            endpoint.recv_frame()

    def test_rejects_zero_length_frame(self):
        endpoint = SocketEndpoint(
            FragmentedSocket((0).to_bytes(4, "big"))
        )

        with self.assertRaises(TransportError):
            endpoint.recv_frame()

    def test_rejects_oversized_incoming_frame(self):
        limit = 8
        header = (limit + 1).to_bytes(4, "big")
        endpoint = SocketEndpoint(
            FragmentedSocket(header),
            max_frame_size=limit,
        )

        with self.assertRaises(TransportError):
            endpoint.recv_frame()

    def test_rejects_empty_outgoing_frame(self):
        endpoint = SocketEndpoint(FragmentedSocket())

        with self.assertRaises(TransportError):
            endpoint.send(b"")

    def test_rejects_oversized_outgoing_frame(self):
        endpoint = SocketEndpoint(
            FragmentedSocket(),
            max_frame_size=4,
        )

        with self.assertRaises(TransportError):
            endpoint.send(b"12345")

    def test_rejects_invalid_frame_limit(self):
        with self.assertRaises(ValueError):
            SocketEndpoint(FragmentedSocket(), max_frame_size=0)

    def test_real_socket_pair_round_trip(self):
        left, right = socket.socketpair()

        try:
            left.settimeout(2)
            right.settimeout(2)

            sender = SocketEndpoint(left)
            receiver = SocketEndpoint(right)

            sender.send(b"real socket round trip")
            self.assertEqual(
                receiver.recv_frame(),
                b"real socket round trip",
            )

            right.shutdown(socket.SHUT_WR)
            self.assertIsNone(sender.recv_frame())

        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
